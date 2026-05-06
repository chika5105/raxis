# RAXIS V2 — Operator-Defined Custom Tools

> **Status:** V2 Specified
>
> **Scope:** This spec is the canonical reference for **operator-defined
> custom tools** — a declarative, plan-bound mechanism for extending the
> agent's tool surface beyond the kernel-provided base tools (`read_file`,
> `bash`, `grep_search`, …) without an SDK, without runtime discovery
> (MCP-style), and without breaking determinism. Custom tools are
> declared inline in `plan.toml`, translated by the planner harness into
> JSON-Schema function definitions, and presented to the LLM on equal
> footing with base tools. Their behavior is implemented by an operator
> command line (typically a script baked into the operator's VM image)
> that reads JSON from stdin and writes a result to stdout.
>
> **Cross-references (canonical homes for adjacent material):**
>
> - `planner-harness.md` — the harness's overall tool-surface model;
>   custom tools are a third tool category alongside base tools and
>   kernel-mediated intents (§3 of that file).
> - `policy-plan-authority.md` — admission-time validation, warning and
>   failure catalog (§3, §3b), `policy.toml` hard caps.
> - `kernel-mechanics-prompt.md` — KSB and NNSP rendering. Custom tools
>   are appended to the JSON `tools` array in the LLM API call alongside
>   base tools and are indistinguishable to the LLM at the protocol
>   level.
> - `vm-network-isolation.md`, `credential-proxy.md` — custom-tool
>   subprocesses share the agent VM's network namespace and are subject
>   to the unified two-tier egress model. No new authority surface.
> - `verifier-processes.md` — the *other* mechanism for running operator
>   code; verifiers are kernel-invoked preflight gates with structured
>   witness output. Custom tools are LLM-invoked utilities. §11 of this
>   spec contrasts the two.
> - `invariants.md` — `INV-PLANNER-HARNESS-04` (Reviewer Custom Tool
>   Prohibition) is mirrored from this spec into the consolidated
>   invariants index.

---

## §1 — Why a Standalone Spec

Three of the structural decisions consolidated in `planner-harness.md`
created a gap operators will hit immediately:

1. **Reviewer was hardened to pure-static** (`INV-PLANNER-HARNESS-01`)
   — no shell, no LSP, no code execution.
2. **Reviewer image was made kernel-canonical**
   (`INV-PLANNER-HARNESS-02`) — operator cannot ship a custom Reviewer
   image with extra tooling.
3. **MCP was rejected** as an authority bypass (no runtime tool
   discovery; tool authority must be plan-bound at admission).

Together these eliminate every ad-hoc path operators historically used
to extend an agent's capabilities. For Executors specifically, this
is too restrictive: real engineering teams need custom utilities
(telemetry analyzers, schema introspectors, internal status APIs,
proprietary linters) that the agent can call structurally rather than
fumbling through `bash` with hand-crafted invocation strings.

**The constraint is explicit:** any extension mechanism must satisfy:

- **Plan-bound and signed.** Tool definitions are part of the plan
  bundle, hashed and signed at submit-time. No runtime discovery.
- **No SDK coupling.** Operators write zero RAXIS-specific code. The
  contract is a one-page JSON-in / output-out shell process.
- **JSON-Schema-shaped.** Custom tools must reach the LLM via the same
  native function-calling protocol as base tools (`read_file`,
  `grep_search`, etc.). Anything weaker (system-prompt-documented
  `bash` invocations) destroys the model's training distribution and
  inflates hallucination rates.
- **Bounded by existing VM authority.** A custom-tool subprocess is
  just another in-VM process — same network namespace, same filesystem
  mounts, same cgroup hierarchy. No new authority surface.
- **Reviewer cannot use them.** Custom tools are arbitrary code
  execution. The Reviewer's pure-static guarantee
  (`INV-PLANNER-HARNESS-01`) must hold structurally; custom tools are
  banned for the Reviewer role.

This spec specifies the mechanism that satisfies all five constraints.

---

## §2 — Scope and Non-Scope

### In scope

- The `[[profiles.<name>.custom_tool]]` declaration schema in
  `plan.toml` (§3).
- The Draft-07 JSON Schema subset accepted for tool input definitions
  (§4).
- The reserved-name list and collision rules (§5).
- The stdin / stdout / stderr wire protocol between the harness and
  the operator command (§6).
- Process containment via cgroup v2, timeout enforcement via
  `cgroup.kill` (§7).
- Profile inheritance and merge semantics (§8).
- Token-budget projection at admission and per-profile count caps
  (§9).
- Reviewer-role prohibition (`INV-PLANNER-HARNESS-04`) (§10).
- Custom tools vs. verifiers — when to use which (§11).
- Audit emission — the `CustomToolInvoked` event schema (§12).
- Cross-spec impacts and the implementation checklist (§13, §14).
- Invariants introduced by this spec (§15).

### Out of scope (explicit)

- **Streaming tool output.** Custom tools return one stdout blob at
  process exit. The LLM's native tool-call protocol does not natively
  support streaming tool results in V2; revisit in V3 if model APIs
  warrant it.
- **Bidirectional tool I/O.** The script reads stdin once, writes
  stdout once, exits. No mid-run callbacks, no stdin re-prompting.
- **Tool composition / chaining inside the harness.** The LLM composes
  tool calls; the harness does not pre-pipe one custom tool into
  another.
- **Host-side custom-tool scripts (Option Y from the design discussion).**
  V2 keeps custom-tool scripts in the operator's VM image. Plan-bundle
  inlining of script bytes (so the operator can ship the script
  alongside `plan.toml` rather than baking it into the image) is
  deferred to V3.
- **Host-network access for custom tools.** A custom-tool subprocess
  uses the VM's network namespace; it has the same egress rights as
  any other in-VM process (Tier 1 tproxy + Tier 2 credential proxy).
  No special carve-outs.
- **Side-effecting state shared across invocations beyond what the
  filesystem provides.** The harness does not maintain per-tool
  caches, sessions, or persistent connections. Each invocation forks
  fresh.

---

## §3 — Plan Declaration Schema

Custom tools are declared on a **profile**, not on a task. The reasoning
is operational: a profile defines the archetype's capability surface
("Frontend Engineer has `npm`, `lint`, `query_telemetry`") and tasks
are tickets assigned to that archetype. You do not teach an engineer a
new tool per Jira ticket; you give them their toolbox once.

### 3.1 Minimum example

```toml
# plan.toml

[profiles.frontend_dev]
inherits_from = "Executor"

[[profiles.frontend_dev.custom_tool]]
name        = "query_telemetry"
description = "Query the internal telemetry service for a target. Returns the raw JSON record."
command     = ["python3", "/usr/local/bin/query_telemetry.py"]

  # JSON Schema (Draft-07 subset) for the LLM-facing input shape.
  [profiles.frontend_dev.custom_tool.schema]
  type = "object"
  required = ["target_id"]
  additionalProperties = false

  [profiles.frontend_dev.custom_tool.schema.properties.target_id]
  type        = "integer"
  description = "Numeric ID of the target to query."

  [profiles.frontend_dev.custom_tool.schema.properties.include_raw]
  type        = "boolean"
  description = "Include raw event payload in the response."
  default     = false
```

### 3.2 Field reference

| Field | Type | Required | Default | Notes |
|---|---|---|---|---|
| `name` | string | yes | — | LLM-visible function name. Must match `^[a-z][a-z0-9_]{0,47}$`. Reserved-name and uniqueness rules per §5. |
| `description` | string | yes | — | LLM-visible function description. Must be 8–800 characters; counts toward the token-budget projection (§9). |
| `command` | array of strings | yes | — | Argv to invoke when the LLM calls the tool. The first element is an absolute path inside the VM filesystem; all elements must be non-empty. The harness invokes via `execvp`-equivalent; **no shell interpolation**. |
| `schema` | object | yes | — | JSON Schema (Draft-07 subset per §4) describing the input object the LLM constructs. The harness sends exactly this object to the script's stdin. |
| `timeout_seconds` | integer | no | `60` | Per-invocation wall-clock cap. Hard-capped by `policy.toml` `max_custom_tool_timeout_seconds` (default 300). |
| `stdin_max_bytes` | integer | no | `262_144` (256 KiB) | Maximum bytes of JSON the harness will send to the script. The LLM's tool input is rejected at the harness boundary if it exceeds this; the LLM receives a `tool_result` error and may retry with a smaller input. |
| `stdout_max_bytes` | integer | no | `65_536` (64 KiB) | Maximum bytes of stdout returned to the LLM. Excess is truncated and the truncation flagged in the `tool_result` (per §6.4). |
| `stderr_max_bytes` | integer | no | `16_384` (16 KiB) | Maximum stderr bytes captured for the audit log. Excess is truncated; truncation flagged in `CustomToolInvoked`. |
| `expose_stderr` | bool | no | `false` | If `true`, the script's stderr is appended to the LLM-facing `tool_result` (after stdout, separated by a sentinel). Stderr is **always** captured in the audit event regardless. |
| `env` | table of string-string | no | `{}` | Additional environment variables to set for the subprocess. Keys must match `^[A-Z][A-Z0-9_]*$`. The harness clears all other env except a small kernel-defined safelist (§6.6). |

> **No host-side script verification.** V2 deliberately omits any
> kernel-side hash verification of the binary at `command[0]`. The
> kernel does not bundle, stage, or inspect the script bytes; the
> script lives exclusively inside the operator's VM image. Operators
> who need supply-chain integrity for their custom-tool scripts pin
> the **entire VM image** by OCI digest:
>
> ```toml
> # policy.toml
> [[vm_images]]
> name             = "my-team/executor"
> oci_digest       = "sha256:abcd1234..."   # pinned image digest
> role_restriction = ["Executor"]
> ```
>
> Image-digest pinning is mathematically equivalent to verifying
> *every* byte of the executor filesystem — script, interpreter,
> shared libraries, libc, and all transitive dependencies — in one
> shot. Per-script hashing covers a strict subset of this surface and
> creates a false sense of security (a tampered Python interpreter
> can subvert a hash-pinned `analyze.py` regardless). The Kernel does
> not babysit the Executor's sandbox: everything inside the
> operator's VM image is the operator's responsibility, and image
> digests are the canonical mechanism for binding it.

### 3.3 Profile-level fields

| Field | Type | Required | Default | Notes |
|---|---|---|---|---|
| `inherits_from` | string | no | — | Parent profile name. Inherited custom tools merge per §8. |
| `custom_tool` | array-of-tables | no | `[]` | Zero or more `[[profiles.<name>.custom_tool]]` blocks. |

A profile MAY declare zero custom tools; this is the common case for
profiles inheriting from `Executor` without extension.

### 3.4 Per-task overrides — explicitly disallowed

`plan.toml` does NOT permit custom-tool declarations under
`[plan.tasks.<id>]`. Custom tools live exclusively at the profile
level. Attempts to declare `[[plan.tasks.<id>.custom_tool]]` are
rejected at admission with `FAIL_CUSTOM_TOOL_TASK_LEVEL_NOT_ALLOWED`.

The reasoning: a task is a unit of work assigned to an archetype, not
a unit of capability definition. Per-task tool overrides would make
the LLM-visible tool surface non-uniform across sibling tasks running
the same profile, breaking caching, audit comparison, and operator
mental model.

---

## §4 — Schema Validation

Custom-tool input schemas are validated at admission time against a
**vendored, deterministic Draft-07 subset**. The subset is chosen for
two properties:

1. **All accepted schemas round-trip through both Anthropic's and
   OpenAI's tool-schema validators without modification.** The harness
   forwards the schema verbatim into the model API request. If we
   accept a schema feature one provider rejects, we ship plans that
   pass admission but crash on first inference.
2. **All accepted schemas are fully resolvable at admission time
   without network access.** No `$ref` to remote URLs, no `$id`-based
   resolution, no dynamic schema fetching. This preserves determinism
   and keeps the kernel's network surface unchanged.

### 4.1 Accepted keywords

The accepted vocabulary is the intersection of Anthropic's and
OpenAI's tool-schema acceptance, restricted further to Draft-07 core:

- **Type:** `type` (must be one of `"object"`, `"string"`, `"integer"`,
  `"number"`, `"boolean"`, `"array"`, `"null"`).
- **Object structure:** `properties`, `required`, `additionalProperties`
  (must be `false` at the root for V2 — the LLM's tool input must be
  fully specified by the declared properties; `true` permits unbounded
  inputs that bypass the declared schema's intent).
- **Array structure:** `items` (single schema only — tuple-typed
  `items: [...]` is rejected as `FAIL_CUSTOM_TOOL_SCHEMA_UNSUPPORTED_FEATURE`).
- **String constraints:** `minLength`, `maxLength`, `pattern` (POSIX
  ERE; no PCRE), `enum`, `format` (only `"uri"`, `"email"`,
  `"date-time"`, `"uuid"` accepted; others rejected).
- **Numeric constraints:** `minimum`, `maximum`, `multipleOf`.
- **Array constraints:** `minItems`, `maxItems`, `uniqueItems`.
- **Documentation:** `description`, `title`, `default`, `examples`
  (all advisory; counted into token-budget projection §9).
- **Conditional and polymorphic constructs:** `enum` only.
  `oneOf` / `anyOf` / `allOf` / `not` / `if` / `then` / `else` are
  rejected as `FAIL_CUSTOM_TOOL_SCHEMA_UNSUPPORTED_FEATURE`. The
  reasoning: model providers handle these inconsistently, and operator
  schemas expressing real polymorphism are rare enough to defer to a
  V3 expansion.

### 4.2 Rejected keywords (always)

| Keyword | Why rejected |
|---|---|
| `$ref`, `$id`, `definitions`, `$defs` | Allows reference resolution, including remote — destroys determinism and contradicts plan-bundle inlining. |
| `oneOf`, `anyOf`, `allOf`, `not` | Provider-inconsistent semantics; rare in practice. |
| `if`, `then`, `else` | Provider-inconsistent semantics; rare in practice. |
| `patternProperties` | Allows unbounded property names; bypasses `additionalProperties: false`. |
| `dependencies`, `dependentRequired`, `dependentSchemas` | Provider-inconsistent semantics. |
| `propertyNames` | Same reasoning as `patternProperties`. |
| `contains` | Provider-inconsistent. |
| `format` other than the four listed in §4.1 | Provider-inconsistent format vocabulary. |

### 4.3 Schema-level admission failures

| Code | Trigger |
|---|---|
| `FAIL_CUSTOM_TOOL_SCHEMA_INVALID` | Schema is not valid JSON / not a valid Draft-07 schema (parser error). |
| `FAIL_CUSTOM_TOOL_SCHEMA_UNSUPPORTED_FEATURE` | Schema uses a keyword listed in §4.2. The error message names the keyword and the reason. |
| `FAIL_CUSTOM_TOOL_SCHEMA_NOT_OBJECT_ROOT` | Top-level `type` is not `"object"`. The LLM's tool-call protocol passes inputs as a single object; non-object root schemas are unrepresentable. |
| `FAIL_CUSTOM_TOOL_SCHEMA_ADDITIONALPROPERTIES_TRUE` | Top-level `additionalProperties` is `true` or omitted. V2 requires `false` for input-shape determinism. |

All failures emit a remediation message naming the offending profile,
tool, and (where applicable) JSON pointer into the schema.

---

## §5 — Reserved Names and Uniqueness

### 5.1 Reserved names

Custom tools MAY NOT use any name reserved by base tools or by the
kernel-mediated intent surface. The reserved list is deterministic and
versioned with the kernel binary:

```
read_file, write_file, edit_file, glob_search, grep_search,
bash, TodoWrite, SubmitReview,
ActivateSubTask, CompleteTask, SingleCommit, IntegrationMerge,
EscalationRequest, InferenceRequest, InitiativeCompleted,
ResolveSubEscalation, ApprovePlan, ApprovePolicy, ApproveWarning,
WebFetch, WebSearch, StructuredOutput, Sleep
```

The full list is exported by the kernel as
`raxis admin reserved-tool-names` for operator inspection.

Violation → `FAIL_CUSTOM_TOOL_NAME_RESERVED { name, profile }`.

### 5.2 Profile-internal uniqueness

Within a single profile (after inheritance merge per §8), custom-tool
`name` values must be unique. Duplicates are rejected with
`FAIL_CUSTOM_TOOL_NAME_COLLISION { name, conflicting_profiles: [...] }`.

### 5.3 Naming convention

The admission check enforces `^[a-z][a-z0-9_]{0,47}$` (lowercase ASCII,
underscore-separated, 1–48 chars). This matches conventions both
Anthropic and OpenAI accept, and rules out names that risk collision
with future base tools (which use snake_case for in-VM tools and
PascalCase for kernel intents — neither overlaps with the enforced
pattern's intersection except by deliberate operator mistake).

---

## §6 — Stdin / Stdout / Stderr Wire Protocol

### 6.1 Invocation

When the LLM emits a `tool_use` block whose `name` matches a custom
tool, the harness:

1. Validates the LLM-supplied `input` object against the declared
   schema. On failure → returns a `tool_result` with `is_error: true`
   and a structured error message; does NOT invoke the script.
2. Allocates a transient cgroup `/sys/fs/cgroup/raxis/customtool-<seq>/`
   (per §7).
3. Forks `command[0]` with `command[1..]` as argv, environment per
   §6.6, current directory set to `/workspace`, stdin connected to a
   pipe, stdout and stderr to separate pipes.
4. Writes the canonical UTF-8 JSON serialization of the LLM's input
   object to the script's stdin and closes the write end. Encoding is
   minified JSON with sorted object keys.
5. Reads stdout and stderr concurrently into bounded buffers
   (`stdout_max_bytes`, `stderr_max_bytes`).
6. Awaits process exit, subject to `timeout_seconds`.
7. Emits the `CustomToolInvoked` audit event (§12).
8. Constructs the LLM-facing `tool_result` (§6.4).

### 6.2 Stdin contract

- **Encoding:** UTF-8.
- **Format:** a single minified JSON value (typically an object) with
  no trailing newline.
- **Closure:** the harness closes stdin after writing. Scripts that
  hang waiting for additional input will hit `timeout_seconds`.
- **Size cap:** `stdin_max_bytes`. The cap applies to the *serialized
  input bytes*, not the LLM-visible token count. The LLM's input
  object is admission-validated against the schema first; a
  schema-valid but oversize input is rare but possible (e.g., a
  pathologically long string field). Such an input is rejected at the
  harness boundary with a `tool_result` error
  `CustomToolInputTooLarge`; the LLM may retry with smaller input.

### 6.3 Stdout convention — accept arbitrary bytes; wrap

Per the design discussion: **the harness does NOT require stdout to be
valid JSON.** It accepts arbitrary UTF-8 bytes (lossy decoding for
non-UTF-8) and wraps them in the `tool_result` content as a string.

Two reasons:

1. The model API tool-result content is ultimately a string; wrapping
   `Hello world\n` as `"Hello world\n"` is exactly what the model
   sees regardless.
2. Forcing valid JSON breaks 90% of trivial scripts (`echo "$result"`,
   `print(value)`). Operator ergonomics matter more than a structural
   guarantee whose only consumer is the LLM's free-form context.

If the operator wants structured JSON in the LLM's view, the script
emits JSON and the LLM is informed (via `description`) that it can
parse it. The harness does not validate.

### 6.4 Stdout cap and truncation

If the script's stdout exceeds `stdout_max_bytes`, the harness keeps
the first `stdout_max_bytes - 256` bytes plus the *last* 256 bytes
(the tail often contains the most informative output — error messages,
final result lines), separated by a clearly-marked truncation sentinel:

```
…[CUSTOM_TOOL_STDOUT_TRUNCATED: original=N_bytes, kept_head=M, kept_tail=256]…
```

The `tool_result` content reflects the truncated stdout. The
`CustomToolInvoked` audit event records the original size and a
SHA-256 of the *full* stdout (which the kernel persists separately if
the operator opts in to full-payload archival; default is digest-only).

### 6.5 Stderr handling

Stderr is **always captured** for the audit log up to
`stderr_max_bytes`. By default it is **NOT exposed to the LLM**
(stderr is notorious for polluting context with progress bars,
deprecation warnings, ANSI color codes, and irrelevant noise that
defeats the LLM's reasoning).

If the operator sets `expose_stderr = true` on a tool declaration,
the harness appends stderr to the LLM-facing `tool_result` content
after stdout, separated by a sentinel:

```
{stdout content}
…[CUSTOM_TOOL_STDERR_BEGIN]…
{stderr content (truncated to stderr_max_bytes if needed)}
…[CUSTOM_TOOL_STDERR_END]…
```

The audit log always records both.

### 6.6 Environment variables

The harness clears the script's environment to a small kernel-defined
safelist before adding the operator's `env` table:

| Variable | Source | Purpose |
|---|---|---|
| `PATH` | Image-default `/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin` | Standard executable search path. |
| `HOME` | `/root` | Subprocess HOME. |
| `LANG` | `C.UTF-8` | Deterministic locale. |
| `RAXIS_CUSTOM_TOOL_NAME` | Tool's `name` field | Lets the script identify which tool it's serving (useful for shared scripts). |
| `RAXIS_TASK_ID` | Current task ID | For audit correlation in operator-side logs. |
| `RAXIS_INVOCATION_ID` | Per-invocation UUID | Matches the audit event's `invocation_id`. |
| `RAXIS_CREDENTIAL_PROXY_*` | Per `credential-proxy.md` | Standard credential proxy localhost ports, if any. |

The operator's `env` table is merged on top. Operator-supplied keys
collide with kernel-supplied keys → admission rejection
(`FAIL_CUSTOM_TOOL_ENV_RESERVED_KEY`).

### 6.7 Exit code semantics

| Exit code | LLM-facing outcome | Audit `outcome` |
|---|---|---|
| `0` | `tool_result` with `is_error: false`, content = stdout (truncated per §6.4) | `Success` |
| `1`–`255` | `tool_result` with `is_error: true`, content = stdout + brief footer naming the exit code | `NonZeroExit { code }` |
| Killed by timeout (cgroup.kill) | `tool_result` with `is_error: true`, content = `[CUSTOM_TOOL_TIMEOUT after Ns]` + stdout-so-far | `Timeout` |
| Killed by session teardown | (no result returned to LLM; the LLM session is being torn down) | `KilledOnTeardown` |
| Stdin too large at admission | `tool_result` with `is_error: true`, structured error | `StdinTooLarge` |
| Stdout truncated at cap | `tool_result` reflects truncated stdout; `is_error` matches exit code | `Success` or `NonZeroExit` with `stdout_truncated: true` flag |

The LLM is expected to handle `is_error: true` by re-planning, just as
it does for any tool failure. Operators are advised to print
human-readable error messages to stdout (which the LLM sees) rather
than relying on stderr (which is hidden by default).

---

## §7 — Process Containment

### 7.1 cgroup substrate (`INV-PLANNER-HARNESS-03`)

Every custom-tool invocation is placed in a transient cgroup
`/sys/fs/cgroup/raxis/customtool-<invocation_seq>/` for the duration
of the call. The cgroup is created before fork, the subprocess is
written to `cgroup.procs` immediately after fork, and the cgroup is
destroyed after the subprocess and all descendants exit.

This reuses the same substrate as backgrounded shells
(`planner-harness.md §5.3`). Linux 5.14+ guest kernel is required
(`INV-PLANNER-HARNESS-03`); the guest-kernel requirement is verified
by `raxis doctor vm-images` per `system-requirements.md §11`.

### 7.2 Termination via `cgroup.kill`

On timeout, session teardown, or explicit cancellation, termination is
performed by writing `1` to the cgroup's `cgroup.kill` file. This is
atomic and race-free against POSIX double-fork daemonization patterns.
The harness verifies `cgroup.events` shows `populated 0` before
returning to the LLM.

`cgroup.kill` semantics are identical to the backgrounded-shell
substrate; this spec does not duplicate the rationale, see
`planner-harness.md §5.3`.

### 7.3 CPU and memory limits

By default, custom-tool subprocesses inherit CPU weight and memory
limits from the planner VM's root cgroup. Operators MAY declare
per-tool limits in a future V2.x extension; V2.0 ships without
per-tool resource caps.

`policy.toml` MAY declare a global `max_concurrent_custom_tool_invocations`
across a single VM (default `4`). Excess concurrent invocations queue
in the harness; queue depth is bounded by `max_queued_custom_tool_invocations`
(default `8`). Queue overflow → the LLM receives a `tool_result` error
`CustomToolConcurrencyExhausted` and may retry.

### 7.4 Filesystem mounts

Custom-tool subprocesses run with the planner VM's mount table
unchanged. They have read-write access to `/workspace` (per the
agent's role; an Executor's `/workspace` is RW, an Orchestrator's is
RO per `planner-harness.md §3`). They can read `/raxis/` (plan-bundle
artifacts, KSB-staged data, credentials per `credential-proxy.md`).

The harness does NOT mount any per-invocation tmpfs. Scripts that
need scratch space use `/tmp` inside the VM (typically a tmpfs in the
operator's image).

---

## §8 — Profile Inheritance and Merge Semantics

### 8.1 Inheritance graph

A profile MAY declare `inherits_from = "<parent>"`. In V2 the
permitted built-in role roots are **`"Executor"`** and **`"Reviewer"`**
(operator-declared Reviewer profiles are permitted but have a tool
surface fixed by `INV-PLANNER-HARNESS-01` — they cannot declare custom
tools, see §10). Profiles attempting `inherits_from = "Orchestrator"`
are rejected at admission with `FAIL_PROFILE_ROLE_NOT_CONFIGURABLE`
because the **Orchestrator** is kernel-managed invisible infrastructure
per `INV-PLANNER-HARNESS-06` (`planner-harness.md §4.8`) — operators
do not declare Orchestrator profiles at all; the kernel auto-creates
the Orchestrator session per initiative.

Inheritance chains are acyclic; cycles are rejected at admission with
`FAIL_PLAN_PROFILE_INHERITANCE_CYCLE`.

### 8.2 Merge rule for `custom_tool` arrays

Custom tools are merged **additively** through the inheritance chain.
The effective custom-tool set for profile `P` is:

```
effective(P) =
    union(custom_tools_declared_directly_on(P),
          effective(parent_of(P)))
```

### 8.3 Name collision is an error

If a child profile declares a custom tool with the same `name` as an
ancestor (or sibling-via-shared-ancestor), the merged set has a
collision and admission fails with `FAIL_CUSTOM_TOOL_NAME_COLLISION
{ name, declaring_profiles: [...] }`.

This rule is intentional: silent override is a configuration footgun.
The expert design discussion converged on **error, not override**:
"If the child needs a different tool, it should name it
`lint_frontend`."

### 8.4 Inheriting from `Reviewer` or `Orchestrator`

Reviewer and Orchestrator have asymmetric treatment under inheritance:

- **`inherits_from = "Reviewer"`** is **permitted** at the inheritance
  graph level (operators can declare `[profiles.<name>]` with this
  parent), but profiles in the resulting Reviewer-rooted subtree MAY
  NOT declare any `custom_tool` blocks. This is enforced at admission
  per `INV-PLANNER-HARNESS-04` (§10) on the *effective role* of the
  profile (the role at the root of the inheritance chain). The check
  surfaces as `FAIL_REVIEWER_CUSTOM_TOOL_NOT_ALLOWED` when violated.

- **`inherits_from = "Orchestrator"`** is **rejected outright** at
  admission with `FAIL_PROFILE_ROLE_NOT_CONFIGURABLE`. The
  Orchestrator is kernel-managed invisible infrastructure per
  `INV-PLANNER-HARNESS-06` (`planner-harness.md §4.8`); there is no
  operator-declared Orchestrator profile concept in V2 to inherit
  from. The custom-tool prohibition is therefore structural — there
  is no Orchestrator-rooted profile that could declare custom tools
  to begin with.

The asymmetry reflects the underlying invariants: Reviewer is a
*configurable role with a fixed tool surface*; Orchestrator is a
*non-configurable role*.

---

## §9 — Token Budget Projection and Count Cap

### 9.1 Per-profile count cap

Each profile may declare at most **25** custom tools (after
inheritance merge). The cap is hard-coded in V2; future versions may
make it configurable. Violation →
`FAIL_CUSTOM_TOOL_COUNT_EXCEEDED { profile, count, limit: 25 }`.

The cap exists to push operators toward composing capability across
multiple profiles / tasks rather than building one mega-agent with
100 tools (which both bloats system prompt and degrades the LLM's
ability to choose the right tool).

### 9.2 Token-budget projection at admission

Custom tools occupy real space in the model's tool-list payload, which
counts against context window. The harness performs a deterministic
token-cost projection at admission:

- Serialize each effective custom tool in the format used in the
  Anthropic / OpenAI tool-list payload (canonical JSON, sorted keys).
- Tokenize using the model-family tokenizer declared in the plan's
  `[provider_aliases.<alias>]` for the profile (per
  `provider-failure-handling.md`).
- Sum across all custom tools.
- Compute `custom_tool_share = sum / context_window_size` for the
  smallest context window across the profile's alias chain.

### 9.3 Threshold gates

| Threshold | Action |
|---|---|
| `< 10%` | Silent. |
| `≥ 10%` AND `< 25%` | `WARN_CUSTOM_TOOL_SCHEMA_BUDGET_HIGH { profile, share, total_tokens }` (per `policy-plan-authority.md §3`). |
| `≥ 25%` | `FAIL_CUSTOM_TOOL_SCHEMA_BUDGET_EXCEEDED { profile, share, total_tokens, limit_share: 0.25 }` (per `policy-plan-authority.md §3b`). |

The 10% / 25% thresholds are V2 defaults. `policy.toml` MAY tighten
(but not loosen) via:

```toml
[custom_tool_limits]
schema_budget_warn_share  = 0.05    # operator wants tighter warning
schema_budget_fail_share  = 0.15    # operator wants tighter rejection
```

Setting either share above the V2 default has no effect — the kernel
takes the more restrictive of (default, policy).

### 9.4 Tokenizer pinning

Token projection uses the tokenizer for the **specific model that
will receive the request**, not a generic estimate. This requires
the kernel to ship the relevant tokenizer tables (Anthropic's BPE
variant, OpenAI's `cl100k_base` / `o200k_base`, etc.) or to call into
the gateway's tokenizer subsystem. V2 implements this via the gateway
(per `provider-failure-handling.md`); the gateway exposes a
`tokenize(model, text) -> u32` admin interface used at admission.

---

## §10 — Reviewer Role Prohibition (`INV-PLANNER-HARNESS-04`)

### 10.1 The invariant

> **`INV-PLANNER-HARNESS-04` — Reviewer Custom Tool Prohibition.** A
> profile whose effective role is `Reviewer` MUST NOT declare any
> `[[profiles.<name>.custom_tool]]` blocks (directly or via
> inheritance). Plan-admission rejects with
> `FAIL_REVIEWER_CUSTOM_TOOL_NOT_ALLOWED { profile, declaring_profiles:
> [...] }`. The check is structural: the admission stage walks the
> inheritance chain, computes the effective custom-tool set, and
> rejects if the effective role is `Reviewer` AND the set is non-empty.

### 10.2 Why this is structural, not optional

A custom tool is arbitrary code execution — a forked subprocess
running operator-defined argv with operator-defined input. It is the
exact attack surface that `INV-PLANNER-HARNESS-01` (Reviewer Code
Execution Prohibition) was designed to eliminate.

The kernel-bundled `raxis-reviewer-core` image
(`INV-PLANNER-HARNESS-02`) does not contain `python3`, `node`,
`bash`, or any shell — so most operator-declared custom-tool commands
would fail at runtime even if admission permitted them. But relying
on "fails at runtime" is wrong defense-in-depth: it produces partial
audit records, surfaces failure to the LLM mid-session, and leaks the
fact that the operator *attempted* to grant code execution to the
Reviewer.

The structural ban catches the misconfiguration at admission, with a
clear remediation message, before any session is created.

### 10.3 Composition with prior invariants

`INV-PLANNER-HARNESS-04` composes with:

- `INV-PLANNER-HARNESS-01` (no Reviewer code execution) — custom tools
  WOULD be code execution; banned at admission.
- `INV-PLANNER-HARNESS-02` (kernel-canonical Reviewer image) — even if
  admission missed a custom tool declaration, the Reviewer image lacks
  the runtimes to execute it. Defense-in-depth.
- `INV-VERIFIER-01..11` (verifier subsystem) — operators who need
  code-running checks for review-time decisions use verifiers, which
  produce structured witness records that flow through the audit
  chain into the Reviewer's KSB. Verifiers are the supported answer
  to "I want operator code to influence Reviewer judgment."

### 10.4 What Reviewer profiles CAN declare

A Reviewer profile MAY still declare:

- `inherits_from = "Reviewer"` (the only legal parent for a Reviewer
  profile).
- Profile-level metadata fields shared with all roles (description,
  budgets, etc.).
- Plan-level review parameters (`symbol_index = "not_needed"`, etc.,
  per `policy-plan-authority.md`).

It MAY NOT declare:

- `[[profiles.<name>.custom_tool]]` (this invariant).
- `vm_image` or any image override (`INV-PLANNER-HARNESS-02`).
- Bash or LSP capability flags (`INV-PLANNER-HARNESS-01` — these are
  not even in the harness binary's Reviewer build target).

### 10.5 Orchestrator: structural impossibility (`INV-PLANNER-HARNESS-06`)

The Orchestrator role's prohibition on custom tools is *structural*,
not declarative: in V2, `plan.toml` cannot contain an
`[profiles.<name>]` whose effective role is `Orchestrator`, and cannot
contain `[plan.tasks.<id>] role = "Orchestrator"`, per
`INV-PLANNER-HARNESS-06` (`planner-harness.md §4.8`). Since there is
no operator-declared Orchestrator profile, there is no surface on
which an operator could attach a `[[profiles.<name>.custom_tool]]`
block targeting the Orchestrator.

Operators who attempt to express "give the Orchestrator a custom tool"
will encounter the rejection at the *profile/task declaration* stage,
not at the custom-tool stage:

- `[profiles.coordinator] role = "Orchestrator"` →
  `FAIL_ORCHESTRATOR_PROFILE_NOT_ALLOWED`.
- `[profiles.coordinator] inherits_from = "Orchestrator"` →
  `FAIL_PROFILE_ROLE_NOT_CONFIGURABLE`.
- `[plan.tasks.merge_things] role = "Orchestrator"` →
  `FAIL_ORCHESTRATOR_TASK_NOT_ALLOWED`.

Each rejection includes a remediation message pointing at
`planner-harness.md §4.8` and noting that the Orchestrator is
kernel-managed.

**Why the Orchestrator's custom-tool ban is structural, not declarative
(unlike the Reviewer's).** The Reviewer is an operator-configurable
role with a *fixed tool surface* — operators DO declare Reviewer
profiles (with prompt overrides, budgets, etc.), and the custom-tool
ban is an explicit `INV-PLANNER-HARNESS-04` admission check. The
Orchestrator is *not operator-configurable at all* — `plan.toml`
literally has no syntactic surface for an Orchestrator profile, so the
custom-tool question never reaches an admission check; it is rejected
one layer up at the profile-declaration layer. The result is the same
(no custom tools for the Orchestrator), but the failure point
(profile-declaration vs custom-tool-declaration) and the failure code
differ.

---

## §11 — Custom Tools vs. Verifiers (When to Use Which)

This is the operator-facing decision tree the spec must answer
unambiguously, because verifiers and custom tools occupy adjacent
semantic territory and confusion is predictable.

| Concern | Verifier (`verifier-processes.md`) | Custom Tool (this spec) |
|---|---|---|
| **Invoked by** | Kernel (preflight, on `CompleteTask`) | LLM (on-demand during a session) |
| **VM** | Dedicated isolated verifier VM | The agent's own VM |
| **Output reaches** | Audit chain (`witness_records`) → Reviewer KSB | LLM context as `tool_result` |
| **Affects review gate?** | Yes — `block_review` failures fail the task; `warn_only` failures surface as KSB witnesses | No — informational to the LLM only |
| **Image** | Operator-published, OCI-pinned, `role_restriction` includes `Verifier` | The Executor profile's image (custom tools are Executor-only in V2 — Reviewer per `INV-PLANNER-HARNESS-04`, Orchestrator per `INV-PLANNER-HARNESS-06`) |
| **Invocation cardinality** | Exactly once per `CompleteTask` per declared verifier | Zero, one, or many times per session at LLM discretion |
| **Network** | Air-gapped by default; explicit `allowed_egress` opt-in | Whatever the agent VM has (tproxy + credential proxy) |
| **Auditability** | `WitnessSubmission` + `VerifierTimedOut` etc. | `CustomToolInvoked` (this spec §12) |
| **Use it for** | Lint, type-check, unit-test, symbol-index — anything that should gate Reviewer judgment | LLM-callable utilities (telemetry lookup, schema introspection, internal status APIs) — anything informational to the LLM's reasoning loop |

**The crisp rule:** if the operator's intent is *"this code-running
check should gate whether the Reviewer is even allowed to look at the
work"*, it's a verifier. If the intent is *"the agent should be able
to ask this on demand while working"*, it's a custom tool.

A future task may be both: the operator declares both a verifier (for
the gate) and a custom tool (for the agent's interactive use during
work). They are not mutually exclusive.

---

## §12 — Audit Event: `CustomToolInvoked`

### 12.1 Schema

Every custom-tool invocation emits exactly one `CustomToolInvoked`
audit event after the subprocess exits (or is killed). The event
hashes into the audit chain per `INV-04`.

```rust
pub enum AuditEventKind {
    // … existing variants …

    CustomToolInvoked {
        session_id:        Uuid,
        task_id:           TaskId,
        profile_name:      String,
        tool_name:         String,
        invocation_id:     Uuid,                  // matches RAXIS_INVOCATION_ID env
        invocation_seq:    u64,                   // monotonic per session
        input_sha256:      [u8; 32],              // of the canonical-JSON stdin bytes
        input_bytes:       u32,
        stdout_sha256:     [u8; 32],              // of the FULL stdout (pre-truncation)
        stdout_bytes:      u32,                   // full size
        stdout_truncated:  bool,                  // true if truncated to stdout_max_bytes
        stderr_sha256:     [u8; 32],              // of the FULL stderr
        stderr_bytes:      u32,
        stderr_truncated:  bool,
        stderr_exposed_to_llm: bool,              // expose_stderr flag
        exit_code:         i32,                   // -1 if killed before exit
        duration_ms:       u64,
        outcome:           CustomToolOutcome,
        cgroup_path:       String,                // /sys/fs/cgroup/raxis/customtool-<seq>/
    },
}

pub enum CustomToolOutcome {
    Success,
    NonZeroExit { code: i32 },
    Timeout,
    KilledOnTeardown,
    StdinTooLarge { input_bytes: u32, limit: u32 },
    InputSchemaValidationFailed { error_summary: String },
    ConcurrencyExhausted,
    SubprocessSpawnFailed { errno: i32 },
}
```

> **Note on integrity attestation.** V2 deliberately does NOT include
> a per-invocation hash of `command[0]` in this event. The script's
> bytes are part of the operator's VM image, whose OCI digest is
> already pinned at policy load (`INV-VM-CAP-03`) and audited via
> `SessionCreated { vm_image_digest }`. The image digest covers every
> byte the script depends on (interpreter, libc, shared libraries,
> the script itself); a per-invocation script hash would be a strict
> subset of that coverage and create the misleading impression that
> the kernel had verified script integrity end-to-end. The supply
> chain is bound at image-pull time, not at tool-call time.

### 12.2 Optional full-payload archival

By default, the kernel persists only the SHA-256 digests of stdin /
stdout / stderr; the full bytes are discarded after the audit event
emits. Operators who require full payload retention for compliance
can opt in via `policy.toml`:

```toml
[audit.custom_tools]
archive_full_payloads        = false   # default
archive_payload_max_bytes    = 1_048_576   # 1 MiB cap when archival is on
```

When `archive_full_payloads = true`, the kernel writes the full
stdin / stdout / stderr bytes to a content-addressed payload store
(`store/audit-payloads/<sha256>.bin`), keyed by the digests in the
audit event. Payloads above `archive_payload_max_bytes` are truncated
with the truncation flagged in a separate `CustomToolPayloadTruncated`
audit event.

This payload archival follows the same lifecycle as
`audit-retention.md` (V3); V2 retains payloads indefinitely.

### 12.3 Operator-facing log surface

The `raxis log` CLI gains a custom-tool view:

```
$ raxis log --filter kind=CustomToolInvoked --task <id>

T+12.4s  query_telemetry  ok  92ms  in=63B out=1.2KiB
T+15.8s  query_telemetry  ok  78ms  in=63B out=1.1KiB
T+18.1s  internal_status  err 215ms in=12B out=234B (exit 1)
```

With `--full`, each line expands to show input/output digests,
truncation state, and the resolved command line.

---

## §13 — Cross-Spec Impacts

### 13.1 Already specified (or being specified in this PR)

| Spec | Change |
|---|---|
| `planner-harness.md` | Add Custom Tools as a third tool category alongside base tools and kernel-mediated intents (extension to §3); list `INV-PLANNER-HARNESS-04` in §13 invariants index. |
| `policy-plan-authority.md` | New `WARN_CUSTOM_TOOL_SCHEMA_BUDGET_HIGH` (§3); new `FAIL_CUSTOM_TOOL_*` codes (§3b); admission check ordering update (§5); `policy.toml` `[custom_tool_limits]` and `[audit.custom_tools]` schema (§4). |
| `kernel-mechanics-prompt.md` | Note that custom tools are appended verbatim to the JSON `tools` array alongside base tools and indistinguishable to the LLM at the protocol level (§3.1, §3.2). Reviewer NNSP confirms no custom tools surface (§3.3). |
| `vm-network-isolation.md` | Cross-reference: custom-tool subprocesses share the agent VM's network namespace and are subject to tproxy + credential proxy enforcement; no new authority surface. |
| `invariants.md` | Add `INV-PLANNER-HARNESS-04` (§10); update count in TOC and preamble; new composition row. |

### 13.2 Future amendments (V2.x or V3)

| Spec | Change | Driver |
|---|---|---|
| `audit-retention.md` (V3) | Custom-tool payload archival lifecycle, retention windows, GC. | `[audit.custom_tools]` policy fields above. |
| `host-capacity.md` | Custom-tool concurrent-invocation limits as a host-aggregate budget category. | If operators report CPU-saturation incidents from runaway concurrent custom tools. |
| `custom-tools.md` (this file) | Per-tool CPU / memory cgroup limits. | V2.x extension; ships when concrete operator demand exists. |

---

## §14 — Implementation Checklist

- [ ] Plan parser accepts `[[profiles.<name>.custom_tool]]` array-of-tables under each profile, with the field schema in §3.2.
- [ ] Plan parser rejects `[[plan.tasks.<id>.custom_tool]]` with `FAIL_CUSTOM_TOOL_TASK_LEVEL_NOT_ALLOWED` (§3.4).
- [ ] Vendored Draft-07 schema validator implementing the accepted-keyword set in §4.1 and rejecting all keywords in §4.2.
- [ ] Reserved-name list mirrored from kernel binary; `raxis admin reserved-tool-names` CLI exposes it.
- [ ] Inheritance walker computes effective custom-tool set; rejects cycles, name collisions, Reviewer-role + non-empty set.
- [ ] Admission emits all `FAIL_*` and `WARN_*` codes per §3, §4.3, §5, §9.3, §10.1.
- [ ] Token-budget projector pulls tokenizer from `raxis-gateway`'s `tokenize(model, text)` admin interface; computes `custom_tool_share` per §9.2.
- [ ] Harness side: schema-validates LLM input before script invocation; constructs canonical-JSON stdin; forks into per-invocation cgroup; enforces stdin/stdout/stderr caps and timeout via `cgroup.kill`.
- [ ] Harness side: builds `tool_result` per §6.4 (truncation sentinel) and §6.5 (stderr exposure rules).
- [ ] Audit event `CustomToolInvoked` per §12.1; emits regardless of outcome.
- [ ] Optional full-payload archival per §12.2 (gated on `[audit.custom_tools] archive_full_payloads`).
- [ ] `raxis log` CLI gains the custom-tool view per §12.3.
- [ ] `raxis-gateway` exposes `tokenize` admin interface (cross-spec dependency).
- [ ] Tests:
      - Plan with valid custom tool → admitted; LLM sees the tool in `tools` array.
      - Plan with reserved-name custom tool → `FAIL_CUSTOM_TOOL_NAME_RESERVED`.
      - Plan with name collision across inherited profile → `FAIL_CUSTOM_TOOL_NAME_COLLISION`.
      - Reviewer profile with custom tool → `FAIL_REVIEWER_CUSTOM_TOOL_NOT_ALLOWED`.
      - Schema with `$ref` → `FAIL_CUSTOM_TOOL_SCHEMA_UNSUPPORTED_FEATURE`.
      - Schema with `oneOf` → `FAIL_CUSTOM_TOOL_SCHEMA_UNSUPPORTED_FEATURE`.
      - Schema with `additionalProperties: true` at root → `FAIL_CUSTOM_TOOL_SCHEMA_ADDITIONALPROPERTIES_TRUE`.
      - 26 custom tools on a profile → `FAIL_CUSTOM_TOOL_COUNT_EXCEEDED`.
      - Custom-tool schemas summing to 26% of context window → `FAIL_CUSTOM_TOOL_SCHEMA_BUDGET_EXCEEDED`.
      - Custom-tool schemas summing to 12% of context window → `WARN_CUSTOM_TOOL_SCHEMA_BUDGET_HIGH` (or admission failure under `--strict`).
      - Custom tool returning non-JSON stdout → `tool_result` content = stdout as-is.
      - Custom tool exceeding `stdout_max_bytes` → truncation sentinel present; full SHA-256 in audit.
      - Custom tool exceeding `timeout_seconds` → cgroup.kill atomic teardown; outcome `Timeout`.
      - Custom tool exiting non-zero → `tool_result.is_error = true`; outcome `NonZeroExit`.
      - Custom tool with `expose_stderr = false` (default) → LLM sees stdout only; audit captures stderr.
      - Custom tool with `expose_stderr = true` → LLM sees stdout + sentinel-bracketed stderr.
      - Custom tool double-fork daemonization → cgroup.kill catches both processes on timeout.
      - Custom tool with operator `env` collision against `RAXIS_*` → `FAIL_CUSTOM_TOOL_ENV_RESERVED_KEY`.
      - Profile inheritance cycle → `FAIL_PLAN_PROFILE_INHERITANCE_CYCLE`.
      - 5 concurrent invocations against `max_concurrent_custom_tool_invocations = 4` → 5th gets `CustomToolConcurrencyExhausted`.
      - Custom tool inside Executor performing HTTP via `urllib` → blocked by tproxy SNI allowlist exactly as bash-invoked HTTP would be.

---

## §15 — Invariants Index

Invariants introduced by this spec:

| Invariant | Statement (one-line) | Section |
|---|---|---|
| `INV-PLANNER-HARNESS-04` | Reviewer Custom Tool Prohibition: profiles with effective role `Reviewer` MUST NOT declare any `[[profiles.<name>.custom_tool]]` blocks (directly or transitively). Plan-admission rejects with `FAIL_REVIEWER_CUSTOM_TOOL_NOT_ALLOWED`. | §10 |

This composes with the existing `INV-PLANNER-HARNESS-*` family:

- **`INV-PLANNER-HARNESS-01`** (no Reviewer code execution) — custom
  tools WOULD be code execution; this invariant catches the
  declaration at admission, before any session is created.
- **`INV-PLANNER-HARNESS-02`** (kernel-canonical Reviewer image) — even
  if admission were bypassed, the canonical image lacks the runtimes
  to execute most operator-declared scripts. Defense-in-depth.
- **`INV-PLANNER-HARNESS-03`** (cgroup v2 process containment) — when
  custom tools DO run (Executor profiles only in V2), they are
  contained in per-invocation cgroups and atomically terminable via
  `cgroup.kill`.
- **`INV-PLANNER-HARNESS-05`** (kernel-canonical Orchestrator image) —
  the Orchestrator image is the kernel's responsibility, parallel to
  the Reviewer image; the operator has no surface on which to attach
  custom tools to it.
- **`INV-PLANNER-HARNESS-06`** (Orchestrator not operator-configurable)
  — there is no operator-declared Orchestrator profile in V2; custom
  tools for the Orchestrator are structurally impossible. This is why
  this spec is an *Executor-only* feature in V2.

And with verifier-side invariants:

- **`INV-VERIFIER-01..11`** — verifiers are the supported answer to
  "I want operator code to influence Reviewer judgment." Custom tools
  serve a different purpose (LLM-on-demand utilities) and explicitly
  do NOT participate in review gating.

---

*Spec complete. Per the standing rule for `INV-PLANNER-HARNESS-*`:
when this file is wrong (i.e., when an implementation choice
contradicts a statement here), the implementation MUST be amended to
conform OR a follow-up amendment to this spec MUST land in the same
PR. Silent divergence between code and this spec is a process
failure.*
